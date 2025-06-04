const { initializeApp } = require('firebase/app');
const { getStorage } = require('firebase/storage');

const firebaseConfig = {
  apiKey: "AIzaSyALDaCZIoa8aswRbSeV7cHAgZWcdECN7oU",
  authDomain: "tathya-36859.firebaseapp.com",
  projectId: "tathya-36859",
  storageBucket: "tathya-36859.firebasestorage.app",
  messagingSenderId: "1028455221079",
  appId: "1:1028455221079:web:4bbe7b597448988d0fa012",
  measurementId: "G-ZSZ79L6RF6"
};

const app = initializeApp(firebaseConfig);
const storage = getStorage(app);

module.exports = { storage };