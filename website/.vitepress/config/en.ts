import { DefaultTheme, LocaleSpecificConfig } from 'vitepress'

export const en: LocaleSpecificConfig<DefaultTheme.Config> & { label: string; lang: string } = {
  label: 'English',
  lang: 'en',
  description: 'Multipath QUIC VPN built on MASQUE CONNECT-IP',

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Guide',
          items: [
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Building', link: '/guide/building' },
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Multipath', link: '/guide/multipath' },
            { text: 'Architecture', link: '/guide/architecture' },
          ],
        },
      ],
    },
  },
}
