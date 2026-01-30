package sftp

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"
)

// Upload 上传入口：支持文件或目录
func (c *Client) Upload(ctx context.Context, localPath, remotePath string, progress ProgressCallback) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local path failed: %w", err)
	}

	if info.IsDir() {
		return c.uploadDirectory(ctx, localPath, remotePath, progress)
	}
	// 检查远程路径是否是目录
	remoteStat, err := c.sftpClient.Stat(remotePath)
	if err == nil && remoteStat.IsDir() {
		// 如果是目录，拼接文件名
		remotePath = c.JoinPath(remotePath, filepath.Base(localPath))
	}
	return c.uploadFile(ctx, localPath, remotePath, info.Size(), info.Mode(), progress)
}

// Download 下载入口：支持文件或目录
func (c *Client) Download(ctx context.Context, remotePath, localPath string, progress ProgressCallback) error {
	info, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		return fmt.Errorf("stat remote path failed: %w", err)
	}

	if info.IsDir() {
		return c.downloadDirectory(ctx, remotePath, localPath, progress)
	}

	stat, err := os.Stat(localPath)
	if err == nil && stat.IsDir() {
		localPath = filepath.Join(localPath, info.Name())
	}

	return c.downloadFile(ctx, remotePath, localPath, info.Size(), info.Mode(), progress)
}

// ================== 单文件多线程分块逻辑 ==================

func (c *Client) uploadFile(ctx context.Context, localPath, remotePath string, size int64, mode os.FileMode, progress ProgressCallback) error {
	// 1. 打开本地文件
	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// 2. 创建远程文件
	dstFile, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// 3. 只有1个线程或文件很小，直接流式传输（减少 overhead）
	if c.config.ThreadsPerFile <= 1 || size < c.config.ChunkSize {
		return c.streamTransfer(srcFile, dstFile, progress)
	}

	// 4. 设置权限
	c.sftpClient.Chmod(remotePath, mode)

	// 5. 多线程分块上传
	g, ctx := errgroup.WithContext(ctx)

	// 计算块数
	// 这里我们不需要预先计算所有块，可以使用 offset 步进
	chunkSize := c.config.ChunkSize

	// 信号量限制并发数
	sem := make(chan struct{}, c.config.ThreadsPerFile)

	for offset := int64(0); offset < size; offset += chunkSize {
		offset := offset  // capture loop var
		sem <- struct{}{} // acquire

		g.Go(func() error {
			defer func() { <-sem }() // release

			// 检查取消
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// 计算当前块大小
			currentChunkSize := chunkSize
			if offset+currentChunkSize > size {
				currentChunkSize = size - offset
			}

			// 读本地 (ReadAt 是并发安全的)
			buf := make([]byte, currentChunkSize)
			n, err := srcFile.ReadAt(buf, offset)
			if err != nil && err != io.EOF {
				return fmt.Errorf("read local at %d failed: %w", offset, err)
			}
			if n == 0 {
				return nil
			}

			// 写远程 (WriteAt 是并发安全的)
			// 注意 buf[:n] 避免 EOF 导致的 buffer 未填满问题
			_, err = dstFile.WriteAt(buf[:n], offset)
			if err != nil {
				return fmt.Errorf("write remote at %d failed: %w", offset, err)
			}

			// 报告进度
			if progress != nil {
				progress(n)
			}
			return nil
		})
	}

	return g.Wait()
}

func (c *Client) downloadFile(ctx context.Context, remotePath, localPath string, size int64, mode os.FileMode, progress ProgressCallback) error {
	srcFile, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if c.config.ThreadsPerFile <= 1 || size < c.config.ChunkSize {
		return c.streamTransfer(srcFile, dstFile, progress)
	}

	os.Chmod(localPath, mode)

	g, ctx := errgroup.WithContext(ctx)
	chunkSize := c.config.ChunkSize
	sem := make(chan struct{}, c.config.ThreadsPerFile)

	for offset := int64(0); offset < size; offset += chunkSize {
		offset := offset
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			currentChunkSize := chunkSize
			if offset+currentChunkSize > size {
				currentChunkSize = size - offset
			}

			buf := make([]byte, currentChunkSize)
			n, err := srcFile.ReadAt(buf, offset)
			if err != nil && err != io.EOF {
				return err
			}
			if n == 0 {
				return nil
			}

			_, err = dstFile.WriteAt(buf[:n], offset)
			if err != nil {
				return err
			}

			if progress != nil {
				progress(n)
			}
			return nil
		})
	}
	return g.Wait()
}

// 简单的流式传输兜底
func (c *Client) streamTransfer(r io.Reader, w io.Writer, progress ProgressCallback) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return wErr
			}
			if progress != nil {
				progress(n)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ================== 目录并发逻辑 ==================

func (c *Client) uploadDirectory(ctx context.Context, localDir, remoteDir string, progress ProgressCallback) error {
	// 1. 确保远程根目录存在
	if err := c.sftpClient.MkdirAll(remoteDir); err != nil {
		// MkdirAll 可能会因为目录已存在报错，可以忽略
	}

	// 2. 遍历本地目录收集文件
	// 为了更好地控制并发，我们先收集文件列表，或者在 Walk 过程中直接分发
	// 使用 errgroup 控制文件级并发
	g, ctx := errgroup.WithContext(ctx)

	// 文件并发限制信号量
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}

		// 拼接远程路径 (注意 SFTP 必须用 forward slash)
		// filepath.ToSlash 用于处理 Windows 路径分隔符
		remoteDest := c.JoinPath(remoteDir, filepath.ToSlash(relPath))

		if info.IsDir() {
			// 目录顺序创建，不走并发
			return c.sftpClient.MkdirAll(remoteDest)
		}

		// 文件：放入并发队列
		// 必须在此处拷贝变量给闭包
		loopPath := path
		loopDest := remoteDest
		loopInfo := info

		// 获取信号量
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.uploadFile(ctx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})

		return nil
	})

	if err != nil {
		return err
	}

	return g.Wait()
}

func (c *Client) downloadDirectory(ctx context.Context, remoteDir, localDir string, progress ProgressCallback) error {
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.config.ConcurrentFiles)

	// 使用 SFTP Walk 遍历
	walker := c.sftpClient.Walk(remoteDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			break
		}

		path := walker.Path()
		info := walker.Stat()

		relPath, err := filepath.Rel(remoteDir, path)
		if err != nil {
			continue // 应该是路径问题，跳过
		}

		localDest := filepath.Join(localDir, relPath)

		if info.IsDir() {
			os.MkdirAll(localDest, info.Mode())
			continue
		}

		loopPath := path
		loopDest := localDest
		loopInfo := info

		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.downloadFile(ctx, loopPath, loopDest, loopInfo.Size(), loopInfo.Mode(), progress)
		})
	}

	return g.Wait()
}
