const resource = [

  /* --- CSS --- */
  '/assets/css/style.css',

  /* --- PWA --- */
  '/app.js',
  '/sw.js',

  /* --- HTML --- */
  '/index.html',
  '/404.html',
  
    '/categories/',
  
    '/tags/',
  
    '/about/',
  
    '/archives/',
  

  /* --- Favicons & compressed JS --- */
  
  
    '/assets/img/favicons/android-chrome-72x72.png',
    '/assets/img/favicons/apple-touch-icon.png',
    '/assets/img/favicons/browserconfig.xml',
    '/assets/img/favicons/favicon-16x16.png',
    '/assets/img/favicons/favicon-32x32.png',
    '/assets/img/favicons/favicon.ico',
    '/assets/img/favicons/mstile-150x150.png',
    '/assets/img/favicons/pito(1).ico',
    '/assets/img/favicons/pito.ico',
    '/assets/img/favicons/site.webmanifest',
    '/assets/js/dist/categories.min.js',
    '/assets/js/dist/commons.min.js',
    '/assets/js/dist/home.min.js',
    '/assets/js/dist/misc.min.js',
    '/assets/js/dist/page.min.js',
    '/assets/js/dist/post.min.js',
    '/assets/js/dist/pvreport.min.js'

];

/* The request url with below domain will be cached */
const allowedDomains = [
  

  'localhost:4000',

  

  'fonts.gstatic.com',
  'fonts.googleapis.com',
  'cdn.jsdelivr.net',
  'polyfill.io'
];

/* Requests that include the following path will be banned */
const denyUrls = [
  
];

