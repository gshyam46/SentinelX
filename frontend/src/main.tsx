import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore – Vite handles CSS imports at build time
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
