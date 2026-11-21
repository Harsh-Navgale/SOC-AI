const THEME_KEY = 'soc_theme'

export function getTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark'
}

export function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem(THEME_KEY, theme)
}

export function toggleTheme() {
  const next = getTheme() === 'light' ? 'dark' : 'light'
  setTheme(next)
  return next
}
