module.exports = function(eleventyConfig) {
  // Remove or comment out the syntax highlight plugin
  // eleventyConfig.addPlugin(require("@11ty/eleventy-plugin-syntaxhighlight"));

  // Passthrough copy for images
  eleventyConfig.addPassthroughCopy("src/posts/*/images/*.{jpg,png,gif}");

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
    // Disable Markdown processing
    markdownTemplateEngine: false,
    templateFormats: ["md", "njk", "html"]
  };
};