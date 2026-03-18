import { defineConfig } from 'vitepress'
import { en } from './en'
import { ja } from './ja'

export default defineConfig({
  title: 'mqvpn',
  lastUpdated: true,
  cleanUrls: true,

  locales: {
    root: en,
    ja: ja,
  },

  themeConfig: {
    socialLinks: [
      { icon: 'github', link: 'https://github.com/mp0rta/mqvpn' },
    ],

    search: {
      provider: 'local',
    },
  },
})
