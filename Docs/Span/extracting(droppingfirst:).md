# extracting(droppingFirst:)

**Instance Method**

> Returns a span over all but the given number of initial elements.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func extracting(droppingFirst k: Int) -> Span<Element>
```

The number of elements to drop from the beginning of the span. k must be greater than or equal to zero.

