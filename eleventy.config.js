const syntaxHighlight = require("@11ty/eleventy-plugin-syntaxhighlight");

module.exports = function(eleventyConfig) {
  eleventyConfig.addPlugin(syntaxHighlight);

  // Passthrough copy for images
  eleventyConfig.addPassthroughCopy("src/posts/*/images/*.{jpg,png,gif}");

  // Custom filter for code highlighting
  eleventyConfig.addFilter("highlightCode", function(content) {
    const hljs = require("highlight.js");
    return content.replace(/<pre><code( class="language-.*?")?>([\s\S]*?)<\/code><\/pre>/g, (match, lang, code) => {
      const language = lang ? lang.replace(' class="language-', '').replace('"', '') : 'text';
      const highlighted = hljs.highlight(code, { language }).value;
      return `<pre><code class="language-${language}">${highlighted}</code></pre>`;
    });
  });

  // Collection for posts
  eleventyConfig.addCollection("posts", function(collectionApi) {
    return collectionApi.getFilteredByGlob("src/posts/*/*.md");
  });

  return {
    dir: {
      input: "src",
      output: "_site",
      includes: "_includes"
    },
    markdownTemplateEngine: "njk",
    templateFormats: ["md", "njk", "html"]
  };
};