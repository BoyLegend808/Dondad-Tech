const mongoose = require('mongoose');

// Prevent model overwrite error
let User;
try {
  User = mongoose.model('User');
} catch (e) {
  User = null;
}

if (User) {
  module.exports = User;
} else {

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, default: "" },
  role: { type: String, default: "user" },
  isEmailVerified: { type: Boolean, default: false },
  verificationToken: { type: String, default: "" },
  googleId: { type: String, default: "" },
  facebookId: { type: String, default: "" },
  profilePicture: { type: String, default: "" },
  resetPasswordToken: { type: String, default: "" },
  resetPasswordExpires: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});

userSchema.index({ email: 1 });
userSchema.index({ googleId: 1 });
userSchema.index({ facebookId: 1 });

  module.exports = mongoose.model('User', userSchema);
}
