# subscript(_:)

**Instance Subscript**

> Accesses the element at the specified position.

**Availability:**
* iOS 26.0+
* iPadOS 26.0+
* Mac Catalyst 26.0+
* macOS 26.0+
* tvOS 26.0+
* visionOS 26.0+
* watchOS 26.0+

```swift
subscript(i: InlineArray<count, Element>.Index) -> Element { get set }
```

The position of the element to access. i must be a valid index of the array that is not equal to the endIndex property.

