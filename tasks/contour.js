module.exports = {
  "templatingLanguage": "html",
  "proxy": null,
  "globals": {},
  "paths": {
    "source": "./source",
    "dest": "./public",
    "templates": "./templates"
  },
  "tasks": {
    "htmlmin": {
      "options": {
        "removeComments": true,
        "collapseWhitespace": true,
        "minifyCSS": true,
        "minifyJS": true,
        "removeEmptyAttributes": false,
        "removeScriptTypeAttributes": true,
        "removeStyleLinkTypeAttributes": true
      }
    },
    "svgo": {
      "options": {}
    },
    "filerev": {
      "ignore": []
    },
    "clean": {
      "ignore": []
    },
    "webpack": {
      "entries": [
        "index",
	"login",
	"txs",
        "config"
      ]
    }
  }
}
