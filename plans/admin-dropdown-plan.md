# Admin Dropdown Menu Plan

## Objective
Change the hamburger slide-in menu to a dropdown menu for the admin panel navigation.

## Current State
- Hamburger button triggers a slide-in panel from the right side
- Nav-links are positioned fixed with `right: -100%` transitioning to `right: 0`

## Desired State
- Hamburger button shows a dropdown menu that appears below the navigation bar
- Dropdown should contain: View Website, Shop Demo, User Greeting, Logout
- Smoother, simpler interaction

## Changes Required

### 1. Update [`admin.html`](admin.html)
- Keep the hamburger button structure
- Add a dropdown container inside `.nav-right` or `.nav-links`
- Structure the dropdown with all navigation options

### 2. Update [`admin.css`](admin.css)
- Remove the slide-in panel styles for `.nav-links`
- Add dropdown styles:
  - `position: absolute`
  - `top: 100%`
  - `right: 0`
  - `min-width: 200px`
  - `background: var(--card-bg)`
  - `box-shadow` for depth
  - `border-radius` for rounded corners
  - `display: none` by default, `display: block` when `.active`
- Animate the dropdown with simple opacity/transform

### 3. Update JavaScript in [`admin.html`](admin.html)
- Toggle `.active` class on the dropdown container instead of nav-links
- Keep click-outside listener to close dropdown

## Visual Design

```
┌─────────────────────────────────────────────────────────┐
│  Dondad Tech Admin    [View Website] [Shop Demo]    [≡]│
├─────────────────────────────────────────────────────────┤
│                                                         │
│  [Hamburger clicked]                                    │
│        ┌────────────────────────┐                        │
│        │  🌐 View Website      │                        │
│        │  🛒 Shop Demo         │                        │
│        │  ─────────────────   │                        │
│        │  👤 Admin Name        │                        │
│        │  🚪 Logout            │                        │
│        └────────────────────────┘                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Implementation Steps

1. **Modify admin.html**
   - Restructure the nav-links to show inline on desktop
   - Add dropdown content wrapper

2. **Modify admin.css**
   - Desktop: Show nav-links inline, hide dropdown
   - Mobile: Hide nav-links, show hamburger, dropdown appears on click

3. **Test**
   - Verify dropdown appears below hamburger
   - Verify click-outside closes dropdown
   - Verify all links work correctly

## Files to Modify
- `admin.html` - Structure and content
- `admin.css` - Styling for dropdown
