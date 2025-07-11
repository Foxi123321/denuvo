# 🚀 Deployment Guide for FreeAI IDE

This guide shows you how to deploy FreeAI IDE to various hosting platforms.

## 📋 Prerequisites

- Modern web browser (Chrome, Firefox, Safari, Edge)
- No server-side requirements (pure client-side application)
- Internet connection for AI features (puter.js)

## 🌐 Quick Local Testing

### Option 1: Direct File Opening
1. Download/clone all files
2. Open `index.html` in your browser
3. Start coding with AI assistance!

### Option 2: Local Server (Recommended)
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx http-server -p 8000 -o

# Using npm script
npm install
npm run serve
```

Then visit: `http://localhost:8000`

## 🚀 Cloud Deployment Options

### 1. GitHub Pages (Free)
```bash
# Setup
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/freeai-ide.git
git push -u origin main

# Enable GitHub Pages in repository settings
# Choose "Deploy from branch" -> "main" -> "/ (root)"
```

Your IDE will be available at: `https://yourusername.github.io/freeai-ide`

### 2. Netlify (Free)
1. Go to [netlify.com](https://netlify.com)
2. Drag and drop your project folder
3. Your IDE is live instantly!

Alternative: Connect your GitHub repository for automatic deployments.

### 3. Vercel (Free)
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Follow prompts
```

### 4. Surge.sh (Free)
```bash
# Install Surge
npm install -g surge

# Deploy
cd your-project-folder
surge

# Choose domain or use generated one
```

### 5. Firebase Hosting (Free)
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login and init
firebase login
firebase init hosting

# Deploy
firebase deploy
```

### 6. AWS S3 + CloudFront
1. Create S3 bucket
2. Enable static website hosting
3. Upload all files
4. Configure CloudFront for global CDN

### 7. DigitalOcean App Platform
1. Connect your GitHub repository
2. Choose static site
3. Deploy automatically

## 📱 Progressive Web App (PWA) Setup

To make FreeAI IDE installable as a desktop/mobile app:

1. Add this to your `index.html` `<head>`:
```html
<link rel="manifest" href="manifest.json">
<meta name="theme-color" content="#007acc">
```

2. Create `manifest.json`:
```json
{
  "name": "FreeAI IDE",
  "short_name": "FreeAI IDE",
  "description": "AI-Powered IDE with Unlimited Free AI",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#1e1e1e",
  "theme_color": "#007acc",
  "icons": [
    {
      "src": "icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

3. Add a service worker for offline functionality (optional)

## 🔧 Custom Domain Setup

### For GitHub Pages:
1. Add `CNAME` file with your domain
2. Configure DNS records:
   - A record: point to GitHub Pages IPs
   - CNAME: point www to yourusername.github.io

### For Other Platforms:
- Most platforms provide custom domain options in their dashboard
- Configure your DNS to point to their servers

## 🛡️ HTTPS & Security

All modern hosting platforms provide HTTPS by default. For custom domains:
- Use Let's Encrypt for free SSL certificates
- Most platforms handle this automatically

## 📊 Analytics & Monitoring

Add Google Analytics or similar:
```html
<!-- Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_MEASUREMENT_ID');
</script>
```

## 🔄 Continuous Deployment

### GitHub Actions (Recommended)
Create `.github/workflows/deploy.yml`:
```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./
```

### Netlify
- Connect GitHub repository
- Auto-deploy on every push to main branch

## 🌍 Global CDN & Performance

For best performance worldwide:
1. Use Cloudflare as CDN
2. Enable compression
3. Optimize images
4. Use HTTP/2

## 📦 Building Distributable Packages

### Electron Desktop App
```bash
npm install electron-builder --save-dev

# Create main.js for Electron
# Package as desktop app
npm run electron-pack
```

### Cordova Mobile App
```bash
npm install -g cordova

# Create mobile app
cordova create freeai-ide-mobile
# Copy web files to www/
cordova platform add android ios
cordova build
```

## 🚨 Troubleshooting

### Common Issues:
1. **AI not working**: Check internet connection and puter.js loading
2. **Files not saving**: Check browser localStorage permissions
3. **CORS errors**: Use a local server instead of file:// protocol
4. **Build failures**: Ensure all dependencies are loaded

### Debug Mode:
- Open browser developer tools (F12)
- Check console for errors
- Verify puter.js is loaded successfully

## 📞 Support

- Check the main README.md for detailed usage
- Open GitHub issues for bugs
- Use the built-in AI assistant for coding help!

---

**Ready to deploy?** Choose your platform and follow the steps above! 🚀