# Admin User Setup Guide

## How to Create Additional Admin Users

### Method 1: Register User, Then Update in MongoDB (Recommended)

1. **Register a new user normally:**
   - Go to `register.html`
   - Fill in the registration form
   - Submit to create a regular user account

2. **Update the user role in MongoDB:**
   
   **Option A: Using MongoDB Compass (GUI)**
   - Open MongoDB Compass
   - Connect to your database
   - Navigate to `dondadtech` database → `users` collection
   - Find the user by email
   - Edit the document and change `role: "user"` to `role: "admin"`
   - Save

   **Option B: Using MongoDB Shell**
   ```javascript
   // Connect to your MongoDB
   use dondadtech
   
   // Update user role to admin
   db.users.updateOne(
     { email: "newemail@example.com" },
     { $set: { role: "admin" } }
   )
   ```

   **Option C: Using Mongoose in Node.js**
   ```javascript
   // Add this temporary endpoint to server.js
   app.post("/api/make-admin", async (req, res) => {
     try {
       const { email } = req.body;
       const user = await User.findOneAndUpdate(
         { email },
         { role: "admin" },
         { new: true }
       );
       if (user) {
         res.json({ success: true, user });
       } else {
         res.status(404).json({ error: "User not found" });
       }
     } catch (error) {
       res.status(500).json({ error: "Failed to update user" });
     }
   });
   ```
   
   Then use Postman or curl:
   ```bash
   curl -X POST http://localhost:3000/api/make-admin \
     -H "Content-Type: application/json" \
     -d '{"email":"newemail@example.com"}'
   ```

3. **Login with the new admin account:**
   - Go to `admin.html`
   - Login with the email and password
   - You should now have admin access

---

### Method 2: Direct Database Insert

Use MongoDB Compass or Shell to insert a new admin user directly:

```javascript
db.users.insertOne({
  name: "New Admin",
  email: "newadmin@dondad.com",
  password: "securepassword123",
  phone: "08012345678",
  role: "admin"
})
```

---

## Default Admin Account

**Email:** `admin@dondad.com`  
**Password:** `admin123`

---

## Admin Link Visibility

The "Admin" link in the navigation is now **only visible to users with `role: "admin"`**.

Regular users will not see the admin link in the navigation menu.

---

## Security Notes

⚠️ **Important:** This system uses plain text passwords stored in MongoDB. For production:
1. Implement password hashing (bcrypt)
2. Add JWT authentication
3. Add session management
4. Implement proper authorization middleware
