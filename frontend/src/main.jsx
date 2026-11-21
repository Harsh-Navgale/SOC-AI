import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
// Self-hosted (no external font CDN — this is a self-hosted security tool, avoid an
// unnecessary runtime dependency on a third-party host for something as basic as type).
import '@fontsource/plus-jakarta-sans/400.css'
import '@fontsource/plus-jakarta-sans/500.css'
import '@fontsource/plus-jakarta-sans/600.css'
import '@fontsource/plus-jakarta-sans/700.css'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
