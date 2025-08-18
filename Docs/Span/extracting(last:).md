# extracting(last:)

**Instance Method**

> Returns a span containing the final elements of the span, up to the given maximum length.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func extracting(last maxLength: Int) -> Span<Element>
```

The maximum number of elements to return. maxLength must be greater than or equal to zero.

