module.exports = function(eleventyConfig) {
  eleventyConfig.addPassthroughCopy("src/posts/**/*.{jpg,png,gif}");
  eleventyConfig.addCollection("posts", function(collectionApi) {
    return collectionApi.getFilteredByGlob("src/posts/*.md");
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