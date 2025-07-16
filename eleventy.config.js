module.exports = function(eleventyConfig) {
  eleventyConfig.addPassthroughCopy("images");
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