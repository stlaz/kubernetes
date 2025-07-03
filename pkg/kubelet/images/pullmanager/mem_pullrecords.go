/*
Copyright 2025 The Kubernetes Authors.

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

package pullmanager

import (
	"sync"
	"sync/atomic"

	kubeletconfiginternal "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/utils/lru"
)

type lruCache[K comparable, V any] struct {
	cache   *lru.Cache
	maxSize int

	// Authoritative indicates if the we can consider the cached records an
	// Authoritative source.
	// False if the cache is full or if there were errors during its initialization.
	Authoritative atomic.Bool

	// ignoreEvictionKeys is a set of keys for which we should't modify the cache's
	// authoritative status during eviction.
	// Each key can only prevent eviction once.
	ignoreEvictionKeys sync.Map
}

func newLRUCache[K comparable, V any](size int) *lruCache[K, V] {
	c := lru.New(size)
	l := &lruCache[K, V]{
		maxSize:            size,
		cache:              c,
		ignoreEvictionKeys: sync.Map{},
	}
	c.SetEvictionFunc(func(key lru.Key, _ any) {
		if _, shouldIgnore := l.ignoreEvictionKeys.Load(key); shouldIgnore {
			return
		}
		// any eviction makes our cache non-authoritative
		l.Authoritative.Store(false)
	})
	return l
}

func (c *lruCache[K, V]) Get(key K) (*V, bool) {
	value, found := c.cache.Get(key)
	if !found {
		return nil, false
	}
	if value == nil {
		return nil, true
	}
	return value.(*V), true
}

func (c *lruCache[K, V]) Set(key K, value *V) { c.cache.Add(key, value) }
func (c *lruCache[K, V]) Delete(key K)        { c.cache.Remove(key) }
func (c *lruCache[K, V]) Len() int            { return c.cache.Len() }
func (c *lruCache[K, V]) Clear()              { c.cache.Clear() }

// NoEvictionDeleteLocked will prevent authoritative cache status changes.
//
// Must be called locked with an external write lock.
func (c *lruCache[K, V]) NoEvictionDeleteLocked(key K) {
	c.ignoreEvictionKeys.Store(key, struct{}{})
	defer c.ignoreEvictionKeys.Delete(key)
	c.Delete(key)
}

// CachedPullRecordsAccessor implements a write-through cache layer on top
// of another PullRecordsAccessor
type CachedPullRecordsAccessor struct {
	delegate PullRecordsAccessor

	intentsLocks       *StripedLockSet
	Intents            *lruCache[string, kubeletconfiginternal.ImagePullIntent]
	pulledRecordsLocks *StripedLockSet
	PulledRecords      *lruCache[string, kubeletconfiginternal.ImagePulledRecord]
}

func NewCachedPullRecordsAccessor(delegate PullRecordsAccessor, intentsCacheSize, pulledRecordsCacheSize, stripedLocksSize int32) *CachedPullRecordsAccessor {
	intentsCacheSize = min(intentsCacheSize, 1024)
	pulledRecordsCacheSize = min(pulledRecordsCacheSize, 2000)

	c := &CachedPullRecordsAccessor{
		delegate: delegate,

		intentsLocks:       NewStripedLockSet(stripedLocksSize),
		Intents:            newLRUCache[string, kubeletconfiginternal.ImagePullIntent](int(intentsCacheSize)),
		pulledRecordsLocks: NewStripedLockSet(stripedLocksSize),
		PulledRecords:      newLRUCache[string, kubeletconfiginternal.ImagePulledRecord](int(pulledRecordsCacheSize)),
	}
	// warm our caches and set authoritative
	c.ListImagePullIntents()
	c.ListImagePulledRecords()
	return c
}

func (c *CachedPullRecordsAccessor) ListImagePullIntents() ([]*kubeletconfiginternal.ImagePullIntent, error) {
	return cacheRefreshingList(
		c.Intents,
		c.intentsLocks,
		c.delegate.ListImagePullIntents,
		pullIntentToCacheKey,
	)
}

func (c *CachedPullRecordsAccessor) ImagePullIntentExists(image string) (bool, error) {
	// do the cheap Get() lock-free
	if _, exists := c.Intents.Get(image); exists {
		return true, nil
	}

	// on a miss, lock on the image
	c.intentsLocks.Lock(image)
	defer c.intentsLocks.Unlock(image)

	// check again if the image exists in the cache under image lock
	if _, exists := c.Intents.Get(image); exists {
		return true, nil
	}
	// if the cache is authoritative, return false on a miss
	if c.Intents.Authoritative.Load() {
		return false, nil
	}

	// fall through to the expensive lookup
	exists, err := c.delegate.ImagePullIntentExists(image)
	if err == nil && exists {
		c.Intents.Set(image, &kubeletconfiginternal.ImagePullIntent{
			Image: image,
		})
	}
	return exists, err
}

func (c *CachedPullRecordsAccessor) WriteImagePullIntent(image string) error {
	c.intentsLocks.Lock(image)
	defer c.intentsLocks.Unlock(image)

	if err := c.delegate.WriteImagePullIntent(image); err != nil {
		return err
	}
	c.Intents.Set(image, &kubeletconfiginternal.ImagePullIntent{
		Image: image,
	})

	return nil
}

func (c *CachedPullRecordsAccessor) DeleteImagePullIntent(image string) error {
	c.intentsLocks.Lock(image)
	defer c.intentsLocks.Unlock(image)

	if err := c.delegate.DeleteImagePullIntent(image); err != nil {
		return err
	}
	c.Intents.NoEvictionDeleteLocked(image)
	return nil
}

func (c *CachedPullRecordsAccessor) ListImagePulledRecords() ([]*kubeletconfiginternal.ImagePulledRecord, error) {
	return cacheRefreshingList(
		c.PulledRecords,
		c.pulledRecordsLocks,
		c.delegate.ListImagePulledRecords,
		pulledRecordToCacheKey,
	)
}

func (c *CachedPullRecordsAccessor) GetImagePulledRecord(imageRef string) (*kubeletconfiginternal.ImagePulledRecord, bool, error) {
	// do the cheap Get() lock-free
	pulledRecord, exists := c.PulledRecords.Get(imageRef)
	if exists {
		return pulledRecord, true, nil
	}

	// on a miss, lock on the imageRef
	c.pulledRecordsLocks.Lock(imageRef)
	defer c.pulledRecordsLocks.Unlock(imageRef)

	// check again if the imageRef exists in the cache under imageRef lock
	pulledRecord, exists = c.PulledRecords.Get(imageRef)
	if exists {
		return pulledRecord, true, nil
	}
	// if the cache is authoritative, return false on a miss
	if c.PulledRecords.Authoritative.Load() {
		return nil, false, nil
	}

	// fall through to the expensive lookup
	pulledRecord, exists, err := c.delegate.GetImagePulledRecord(imageRef)
	if err == nil && exists {
		c.PulledRecords.Set(imageRef, pulledRecord)
	}
	return pulledRecord, exists, err
}

func (c *CachedPullRecordsAccessor) WriteImagePulledRecord(record *kubeletconfiginternal.ImagePulledRecord) error {
	c.pulledRecordsLocks.Lock(record.ImageRef)
	defer c.pulledRecordsLocks.Unlock(record.ImageRef)

	if err := c.delegate.WriteImagePulledRecord(record); err != nil {
		return err
	}
	c.PulledRecords.Set(record.ImageRef, record)
	return nil
}

func (c *CachedPullRecordsAccessor) DeleteImagePulledRecord(imageRef string) error {
	c.pulledRecordsLocks.Lock(imageRef)
	defer c.pulledRecordsLocks.Unlock(imageRef)

	if err := c.delegate.DeleteImagePulledRecord(imageRef); err != nil {
		return err
	}
	c.PulledRecords.NoEvictionDeleteLocked(imageRef)
	return nil
}

func cacheRefreshingList[K comparable, V any](
	cache *lruCache[K, V],
	delegateLocks *StripedLockSet,
	listRecordsFunc func() ([]*V, error),
	recordToKey func(*V) K,
) ([]*V, error) {
	wasAuthoritative := cache.Authoritative.Load()
	if !wasAuthoritative {
		// doing a full list gives us an opportunity to become authoritative
		// if we get back an error-free result that fits in our cache
		delegateLocks.GlobalLock()
		defer delegateLocks.GlobalUnlock()
	}

	results, err := listRecordsFunc()
	if wasAuthoritative {
		return results, err
	}

	resultsAreAuthoritative := err == nil && len(results) <= cache.maxSize
	// populate the cache if that would make our cache authoritative or if the cache is currently empty
	if resultsAreAuthoritative || cache.Len() == 0 {
		cache.Clear()
		// populate up to maxSize results in the cache
		for _, record := range results[:min(len(results), cache.maxSize)] {
			cache.Set(recordToKey(record), record)
		}
		cache.Authoritative.Store(resultsAreAuthoritative)
	}

	return results, err
}

func pullIntentToCacheKey(intent *kubeletconfiginternal.ImagePullIntent) string {
	return intent.Image
}

func pulledRecordToCacheKey(record *kubeletconfiginternal.ImagePulledRecord) string {
	return record.ImageRef
}
