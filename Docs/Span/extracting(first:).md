# extracting(first:)

**Instance Method**

> Returns a span containing the initial elements of this span, up to the specified maximum length.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func extracting(first maxLength: Int) -> Span<Element>
```

The maximum number of elements to return. maxLength must be greater than or equal to zero.

