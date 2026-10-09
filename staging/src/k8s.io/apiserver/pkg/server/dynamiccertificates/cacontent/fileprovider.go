/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cacontent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// fileCAContentAccessor watches a file and adds workqueue items when the file changes
type fileCAContentAccessor struct {
	filename string
}

func NewFileCAContentAccessor(path string) CAContentAccessor {
	return &fileCAContentAccessor{
		filename: path,
	}
}

func (c *fileCAContentAccessor) Watch(ctx context.Context, queue workqueue.TypedRateLimitingInterface[struct{}]) {
	// start the loop that watches the CA file until stopCh is closed.
	go wait.Until(func() {
		if err := c.watchCAFile(ctx.Done(), queue); err != nil {
			klog.ErrorS(err, "Failed to watch CA file, will retry later")
		}
	}, time.Minute, ctx.Done())
}

func (c *fileCAContentAccessor) GetPEMBundle() ([]byte, error) {
	return os.ReadFile(c.filename)
}

func (c *fileCAContentAccessor) watchCAFile(stopCh <-chan struct{}, q workqueue.TypedRateLimitingInterface[struct{}]) error {
	// Trigger a check here to ensure the content will be checked periodically even if the following watch fails.
	q.Add(struct{}{})

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %v", err)
	}
	defer w.Close()

	if err = w.Add(c.filename); err != nil {
		return fmt.Errorf("error adding watch for file %s: %v", c.filename, err)
	}
	// Trigger a check in case the file is updated before the watch starts.
	q.Add(struct{}{})

	for {
		select {
		case e := <-w.Events:
			if err := c.handleWatchEvent(q, e, w); err != nil {
				return err
			}
		case err := <-w.Errors:
			return fmt.Errorf("received fsnotify error: %v", err)
		case <-stopCh:
			return nil
		}
	}
}

// handleWatchEvent triggers reloading the CA file, and restarts a new watch if it's a Remove or Rename event.
func (c *fileCAContentAccessor) handleWatchEvent(q workqueue.TypedRateLimitingInterface[struct{}], e fsnotify.Event, w *fsnotify.Watcher) error {
	// This should be executed after restarting the watch (if applicable) to ensure no file event will be missing.
	defer q.Add(struct{}{})
	if !e.Has(fsnotify.Remove) && !e.Has(fsnotify.Rename) {
		return nil
	}
	if err := w.Remove(c.filename); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
		klog.InfoS("Failed to remove file watch, it may have been deleted", "file", c.filename, "err", err)
	}
	if err := w.Add(c.filename); err != nil {
		return fmt.Errorf("error adding watch for file %s: %v", c.filename, err)
	}
	return nil
}
