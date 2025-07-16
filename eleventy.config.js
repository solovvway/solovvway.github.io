module.exports = function(eleventyConfig) {
  // Add escape filter for JavaScript string
  eleventyConfig.addFilter("jsStringEscape", function(content) {
    return content
      .replace(/\\/g, '\\\\') // Escape backslashes
      .replace(/`/g, '\\`')   // Escape backticks
      .replace(/\${/g, '\\${') // Escape template literals
      .replace(/'/g, "\\'")   // Escape single quotes
      .replace(/"/g, '\\"')   // Escape double quotes
      .replace(/\n/g, '\\n')  // Escape newlines
      .replace(/\r/g, '\\r'); // Escape carriage returns
  });

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
    markdownTemplateEngine: false, // Disable Markdown processing
    templateFormats: ["md", "njk", "html"]
  };
};