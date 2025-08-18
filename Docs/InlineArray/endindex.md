# endIndex

**Instance Property**

> The array’s “past the end” position—that is, the position one greater than the last valid subscript argument.

**Availability:**
* iOS 26.0+
* iPadOS 26.0+
* Mac Catalyst 26.0+
* macOS 26.0+
* tvOS 26.0+
* visionOS 26.0+
* watchOS 26.0+

```swift
var endIndex: InlineArray<count, Element>.Index { get }
```

## Discussion

If the array is empty, endIndex is equal to startIndex.

