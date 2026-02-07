# SecureChat - Premium UI Design

## Design Philosophy

**Better than WhatsApp & Signal** through:
- Glassmorphism + depth
- Fluid micro-animations
- Premium dark mode
- Buttery 60fps interactions

---

## Mockups

### Chat Screen
![Premium chat interface](/Users/peter2/.gemini/antigravity/brain/9d81a019-6e71-4a38-b6fa-c4ab79d4f9f3/chat_screen_premium_1770505395301.png)

### Contacts List
![Premium contacts list](/Users/peter2/.gemini/antigravity/brain/9d81a019-6e71-4a38-b6fa-c4ab79d4f9f3/contacts_screen_premium_1770505415397.png)

---

## Color System

| Token | Value | Usage |
|-------|-------|-------|
| `bg-primary` | `#0D0D1A` | Main background |
| `bg-secondary` | `#1A1A2E` | Cards |
| `accent-start` | `#7B2FFF` | Gradient start |
| `accent-end` | `#00D4FF` | Gradient end |
| `glass` | `rgba(255,255,255,0.08)` | Glassmorphism |

---

## Animations

### Message Send
```
1. Text shrinks slightly (scale: 0.98)
2. Bubble appears from bottom with spring physics
3. Gradient shimmer sweeps across bubble
4. Checkmark fades in with bounce
Duration: 400ms | Easing: spring(1, 80, 10)
```

### Message Receive
```
1. Bubble slides in from left with blur
2. Blur clears as it settles
3. Subtle pulse on avatar
Duration: 350ms | Easing: easeOutExpo
```

### Typing Indicator
```
Three dots with staggered bounce
Delay: 150ms between dots
Loop: infinite while typing
```

### Screen Transitions
```
Push: Slide + fade with parallax (background moves slower)
Pop: Reverse with slight scale-down
Duration: 300ms | Easing: easeInOutCubic
```

### Pull-to-Refresh
```
Custom animation: Lock icon unlocks → spins → relocks
Haptic feedback at threshold
```

### Contact Online Status
```
Green ring pulses softly (opacity 0.5 → 1.0)
Glow radiates outward
Period: 2s | Loop: infinite
```

---

## SwiftUI Implementation Notes

```swift
// Spring animation for messages
.animation(.spring(response: 0.4, dampingFraction: 0.7))

// Gradient message bubble
.background(
    LinearGradient(
        colors: [.purple, .blue],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
)

// Glassmorphism effect
.background(.ultraThinMaterial)
.background(Color.white.opacity(0.08))
```

---

## Haptic Feedback

| Action | Haptic |
|--------|--------|
| Send message | `.impact(.light)` |
| Pull refresh | `.impact(.medium)` |
| Long press | `.impact(.heavy)` |
| Error | `.notificationOccurred(.error)` |
| Success | `.notificationOccurred(.success)` |
