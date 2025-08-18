# subscript(_:)

**Instance Subscript**

> Accesses the element at the specified position in the Span.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
subscript(position: Span<Element>.Index) -> Element { get }
```

The offset of the element to access. position must be greater or equal to zero, and less than count.

