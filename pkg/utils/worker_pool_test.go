package utils

import (
	"sync/atomic"
	"testing"
)

func TestWorkerPool_AllTasksComplete(t *testing.T) {
	wp := NewWorkerPool(5)
	var count atomic.Int32
	total := 50

	for range total {
		wp.Execute(func() {
			count.Add(1)
		})
	}
	wp.Wait()

	if got := int(count.Load()); got != total {
		t.Errorf("completed %d tasks, want %d", got, total)
	}
}

func TestWorkerPool_ConcurrencyLimit(t *testing.T) {
	wp := NewWorkerPool(3)
	var current atomic.Int32
	var maxSeen atomic.Int32

	for range 20 {
		wp.Execute(func() {
			cur := current.Add(1)
			// 粗略检查：记录看到的最大并发数
			for {
				old := maxSeen.Load()
				if cur <= old || maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			// 模拟消耗一点时间让并发真正发生
			for i := 0; i < 10000; i++ {
				_ = i
			}
			current.Add(-1)
		})
	}
	wp.Wait()

	if m := int(maxSeen.Load()); m > 3 {
		t.Errorf("max concurrency was %d, limit is 3", m)
	}
}

func TestWorkerPool_ZeroConcurrency_DefaultsTo5(t *testing.T) {
	// 不应该 panic，应默认为 5
	wp := NewWorkerPool(0)
	var done atomic.Bool

	wp.Execute(func() {
		done.Store(true)
	})
	wp.Wait()

	if !done.Load() {
		t.Error("task did not complete with zero concurrency")
	}
}

func TestWorkerPool_PanicHandler(t *testing.T) {
	var caught atomic.Value

	wp := NewWorkerPool(2, WithPanicHandler(func(r any) {
		caught.Store(r)
	}))

	wp.Execute(func() {
		panic("boom")
	})
	wp.Wait()

	if v := caught.Load(); v == nil {
		t.Error("panic was not caught by handler")
	} else if v != "boom" {
		t.Errorf("caught panic = %v, want 'boom'", v)
	}
}
