# extracting(_:)

**Instance Method**

> Constructs a new span over the items within the supplied range of positions within this span.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func extracting(_ bounds: Range<Span<Element>.Index>) -> Span<Element>
```

A valid range of positions. Every position in this range must be within the bounds of this Span.

