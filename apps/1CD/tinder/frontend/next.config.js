//@ts-check

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { composePlugins, withNx } = require('@nx/next');

/**
 * @type {import('@nx/next/plugins/with-nx').WithNxOptions}
 **/
const nextConfig = {
  nx: {
    svgr: false,
  },
  images: {
    dangerouslyAllowSVG: true,
    remotePatterns: [
      {
        hostname: '*',
      },
    ],
  },
  env: {
    BACKEND_URI: process.env.BACKEND_URI || '',
    LOCAL_BACKEND_URI: process.env.LOCAL_BACKEND_URI || '',
    MOCK_TOKEN: process.env.MOCK_TOKEN || '',
  },
};

const plugins = [withNx];

module.exports = composePlugins(...plugins)(nextConfig);
