# init(_:)

**Initializer**

> Initializes every element in this array, by calling the given closure with each index.

**Availability:**
* iOS 26.0+
* iPadOS 26.0+
* Mac Catalyst 26.0+
* macOS 26.0+
* tvOS 26.0+
* visionOS 26.0+
* watchOS 26.0+

```swift
init<E>(_ body: (InlineArray<count, Element>.Index) throws(E) -> Element) throws(E) where E : Error
```

A closure that returns an owned Element to emplace at the passed in index.

