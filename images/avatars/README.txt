# Default Profile Pictures

Add your 5 default profile pictures here.

## Instructions:
1. Add 5 image files to this folder
2. Name them exactly:
   - `avatar-1.png` (or .jpg, .svg)
   - `avatar-2.png`
   - `avatar-3.png`
   - `avatar-4.png`
   - `avatar-5.png`

3. Then update server.js line ~2870 to point to these images:
   ```javascript
   { id: 1, url: "/images/avatars/avatar-1.png", name: "Blue" },
   { id: 2, url: "/images/avatars/avatar-2.png", name: "Green" },
   { id: 3, url: "/images/avatars/avatar-3.png", name: "Red" },
   { id: 4, url: "/images/avatars/avatar-4.png", name: "Purple" },
   { id: 5, url: "/images/avatars/avatar-5.png", name: "Orange" }
   ```

## Tips:
- Use square images (recommended: 200x200 or 400x400 pixels)
- PNG or JPG format works best
- Make sure the images are appropriate for all ages
