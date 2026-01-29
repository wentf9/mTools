package file

import (
	"os"
	"path/filepath"
)

// CreateFileRecursive 递归创建文件并写入内容
func CreateFileRecursive(filePath string, content []byte, perm os.FileMode) error {
	// 创建目录
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建文件（使用指定权限）
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入内容
	if content != nil {
		if _, err := file.Write(content); err != nil {
			return err
		}
	}

	return nil
}
