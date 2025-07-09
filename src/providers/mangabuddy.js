const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

/**
 * Fetch an image from the given URL with MangaBuddy-specific headers.
 * @param {string} url
 * @returns {Promise<Buffer>} Raw image bytes
 */
async function fetchMangabuddyImage(url) {
  if (!url) {
    throw new Error('No URL provided');
  }

  const response = await fetch(url, {
    headers: {
      Referer: 'https://mangabuddy.com/',
      'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch image: ${response.status} ${response.statusText}`);
  }

  return response.buffer();
}

module.exports = { fetchMangabuddyImage };
