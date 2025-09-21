Absolutely Ali — let’s break down **PHP Magic Methods** that are  **invoked automatically** . These are special methods in PHP that start with double underscores (`__`) and are triggered by specific actions or behaviors in your code. They’re part of PHP’s **object-oriented programming (OOP)** model and allow you to customize how objects behave.

---

## 🧠 What Are PHP Magic Methods?

Magic methods are **built-in hooks** that PHP calls **automatically** when certain events occur in an object.

They’re not called manually — they’re triggered by the engine based on context.

> Think of them as “event listeners” inside your class — they respond to things like creating, accessing, or destroying objects.

---

## 🔄 Automatically Invoked Magic Methods

Here’s a complete list of PHP magic methods that are  **automatically triggered** :

### 1️⃣ `__construct()`

* Called when an object is  **instantiated** .

```php
class User {
  public function __construct() {
    echo "User created!";
  }
}
```

### 2️⃣ `__destruct()`

* Called when an object is **destroyed** or script ends.

```php
public function __destruct() {
  echo "User destroyed!";
}
```

### 3️⃣ `__call($name, $arguments)`

* Called when invoking  **undefined or inaccessible methods** .

```php
public function __call($name, $arguments) {
  echo "Method $name does not exist.";
}
```

### 4️⃣ `__callStatic($name, $arguments)`

* Same as `__call()`, but for  **static methods** .

```php
public static function __callStatic($name, $arguments) {
  echo "Static method $name does not exist.";
}
```

### 5️⃣ `__get($property)`

* Called when accessing an  **undefined or inaccessible property** .

```php
public function __get($property) {
  echo "Getting $property";
}
```

### 6️⃣ `__set($property, $value)`

* Called when setting an  **undefined or inaccessible property** .

```php
public function __set($property, $value) {
  echo "Setting $property to $value";
}
```

### 7️⃣ `__isset($property)`

* Called when using `isset()` on an undefined property.

```php
public function __isset($property) {
  return false;
}
```

### 8️⃣ `__unset($property)`

* Called when using `unset()` on an undefined property.

```php
public function __unset($property) {
  echo "Unsetting $property";
}
```

### 9️⃣ `__toString()`

* Called when an object is treated as a  **string** .

```php
public function __toString() {
  return "User object";
}
```

### 🔟 `__invoke()`

* Called when an object is used as a  **function** .

```php
public function __invoke($arg) {
  echo "Invoked with $arg";
}
```

### 1️⃣1️⃣ `__clone()`

* Called when an object is **cloned** using `clone`.

```php
public function __clone() {
  echo "Object cloned";
}
```

### 1️⃣2️⃣ `__sleep()` and `__wakeup()`

* Used during **serialization** and  **unserialization** .

```php
public function __sleep() {
  return ['property1', 'property2'];
}
public function __wakeup() {
  echo "Object unserialized";
}
```

### 1️⃣3️⃣ `__debugInfo()`

* Called when using `var_dump()` on an object.

```php
public function __debugInfo() {
  return ['info' => 'custom debug'];
}
```

---

## 🧰 Why Use Magic Methods?

| Purpose            | Benefit                             |
| ------------------ | ----------------------------------- |
| Object lifecycle   | Customize creation and destruction  |
| Dynamic behavior   | Handle undefined properties/methods |
| Debugging          | Control output of `var_dump()`    |
| Serialization      | Manage object persistence           |
| Functional objects | Use objects like functions          |

---

## ⚠️ Best Practices

* Use magic methods **sparingly** — they can make code harder to debug.
* Always document their behavior clearly.
* Avoid overloading logic in `__get()` or `__call()` — it can lead to hidden bugs.
* Prefer explicit methods when possible.

---

## ✅ Final Summary

| Method                          | Trigger                   |
| ------------------------------- | ------------------------- |
| `__construct()`               | Object creation           |
| `__destruct()`                | Object destruction        |
| `__call()`/`__callStatic()` | Undefined method call     |
| `__get()`/`__set()`         | Undefined property access |
| `__isset()`/`__unset()`     | Property check or removal |
| `__toString()`                | Object as string          |
| `__invoke()`                  | Object as function        |
| `__clone()`                   | Object cloning            |
| `__sleep()`/`__wakeup()`    | Serialization             |
| `__debugInfo()`               | Debug output              |

> Magic methods are like **hidden gears** in PHP’s object engine — they let you fine-tune how your objects behave behind the scenes.

---

Ali — if you want, I can now help you  **build a class using magic methods** , simulate  **dynamic property access** , or write a **custom object handler** using `__invoke()` or `__call()`. Just say the word!
