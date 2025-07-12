# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel. This project
benefits from the expertise of security researchers around the world.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Build and test your changes
4. Submit a pull request

## Build Instructions

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

## Code Style

- C++17 standard
- 4-space indentation
- `snake_case` for C API functions (prefixed with `sentinel_`)
- `PascalCase` for C++ classes
- All public headers must be self-contained (include their own dependencies)
- Windows API calls should be wrapped with proper error checking
- Non-Windows platforms should have stub implementations

## What We Accept

- New detection vector analysis
- Additional anti-cheat system support
- Performance improvements
- Bug fixes with test cases
- Documentation improvements
- New signature patterns

## What We Do Not Accept

- Code designed for use in live cheating
- Exploits targeting specific games
- Malicious payloads or backdoors
- Code without proper error handling

## Testing

Please add unit tests for new functionality:

```cpp
// tests/test_my_feature.cpp
#include "sentinel/sentinel.h"
#include <cassert>

int main() {
    sentinel_init();
    // Your tests here
    sentinel_shutdown();
    return 0;
}
```

## Research Ethics

All contributions must adhere to responsible disclosure practices.
If your contribution involves findings about a specific anti-cheat
system, ensure the vendor has been notified before inclusion.

## License

By contributing, you agree that your contributions will be licensed
under the MIT License.
