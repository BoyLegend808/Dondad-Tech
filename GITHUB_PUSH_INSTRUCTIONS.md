# How to Push to GitHub

## Step 1: Create Repository on GitHub

1. Go to https://github.com/new
2. **Owner**: Select "Ecommerce" from the dropdown
3. **Repository name**: Type `Tech-Shop`
4. **Description**: "Dondad Tech E-commerce Store"
5. **Public**: Select "Public"
6. **DO NOT** check "Add a README file" (we already have one)
7. Click "Create repository"

## Step 2: Push Your Code

Run these commands in your terminal:

```bash
cd "c:/Users/HP/OneDrive/Documenten/Legends Codes/Dondad Tech"

# Rename the remote to proper origin (if needed)
git remote remove origin 2>nul
git remote add origin https://github.com/Ecommerce/Tech-Shop.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## Step 3: Enable GitHub Pages (for free hosting)

1. Go to your repository: https://github.com/Ecommerce/Tech-Shop
2. Click **Settings** tab
3. Click **Pages** in the left sidebar
4. Under "Source", select **"Deploy from a branch"**
5. Under "Branch", select **"main"** and **"/ (root)"**
6. Click **Save**
7. Wait 1-2 minutes, then your site will be live at: https://Ecommerce.github.io/Tech-Shop/

## Step 4: Share Your Site

Your e-commerce store will be publicly accessible at:
- **URL**: https://Ecommerce.github.io/Tech-Shop/
- **Repository**: https://github.com/Ecommerce/Tech-Shop

## Important Notes

- User accounts are stored in localStorage (browser-specific)
- For real user accounts across devices, you'll need a backend server
- GitHub Pages hosts static files only (HTML, CSS, JavaScript)
