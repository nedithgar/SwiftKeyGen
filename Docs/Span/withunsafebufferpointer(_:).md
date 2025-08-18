# withUnsafeBufferPointer(_:)

**Instance Method**

> Calls a closure with a pointer to the viewed contiguous storage.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func withUnsafeBufferPointer<E, Result>(_ body: (UnsafeBufferPointer<Element>) throws(E) -> Result) throws(E) -> Result where E : Error, Result : ~Copyable
```

A closure with an UnsafeBufferPointer parameter that points to the viewed contiguous storage. If body has a return value, that value is also used as the return value for the withUnsafeBufferPointer(_:) method. The closure’s parameter is valid only for the duration of its execution.

