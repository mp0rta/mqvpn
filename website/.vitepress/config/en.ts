import { DefaultTheme, LocaleSpecificConfig } from 'vitepress'

export const en: LocaleSpecificConfig<DefaultTheme.Config> & { label: string; lang: string } = {
  label: 'English',
  lang: 'en',
  description: 'Modern multipath VPN built on open standards',

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Benchmarks', link: '/benchmarks' },
    ],

    footer: {
      message: 'Released under the Apache License 2.0',
      copyright: 'Provided "AS IS" without warranty of any kind. Use at your own risk.',
    },

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
