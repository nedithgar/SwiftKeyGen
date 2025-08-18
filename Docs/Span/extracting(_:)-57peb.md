# extracting(_:)

**Instance Method**

> Constructs a new span over all the items of this span.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
func extracting(_: (UnboundedRange_) -> ()) -> Span<Element>
```

## Return Value

A Span over all the items of this span.

