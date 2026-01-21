package utils

import "sync"

// WorkerPool 控制并发任务的执行
type WorkerPool interface {
	Execute(task func())
	Wait()
}

type defaultWorkerPool struct {
	limit        chan struct{}
	wg           sync.WaitGroup
	panicHandler func(any)
}

type Option func(*defaultWorkerPool)

// WithPanicHandler 允许用户自定义 panic 处理逻辑
func WithPanicHandler(handler func(any)) Option {
	return func(wp *defaultWorkerPool) {
		wp.panicHandler = handler
	}
}

func NewWorkerPool(maxConcurrent uint, options ...Option) WorkerPool {
	if maxConcurrent == 0 {
		maxConcurrent = 5
	}
	wp := &defaultWorkerPool{
		limit: make(chan struct{}, maxConcurrent),
	}
	for _, option := range options {
		option(wp)
	}
	return wp
}

// Execute 提交一个任务到工作池,和sync.WaitGroup.Go()用法一致
func (wp *defaultWorkerPool) Execute(task func()) {
	wp.wg.Go(func() {
		// 获取许可
		wp.limit <- struct{}{}
		defer func() { <-wp.limit }()
		if wp.panicHandler != nil {
			// 捕获 panic
			defer func() {
				if r := recover(); r != nil {
					wp.panicHandler(r)
				}
			}()
		}
		task()
	})
}

func (wp *defaultWorkerPool) Wait() {
	wp.wg.Wait()
}
