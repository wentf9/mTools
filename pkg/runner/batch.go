package runner

import (
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils"
)

type TaskFunc func(host models.Node) error

type Result struct {
	Host  models.Node
	Error error
}

func RunParallel(hosts []models.Node, concurrency uint, task TaskFunc) <-chan Result {
	wp := utils.NewWorkerPool(concurrency)
	// 创建结果通道，缓冲区大小设为 host 数量，防止阻塞 worker
	results := make(chan Result, len(hosts))
	go func() {
		for _, host := range hosts {
			wp.Execute(func() {
				err := task(host)
				results <- Result{Host: host, Error: err}
			})
		}
		wp.Wait()
		close(results)
	}()
	return results
}
