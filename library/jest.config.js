module.exports = {
  moduleFileExtensions: [
    "js",
    "json",
    "ts"
  ],
  rootDir: "src",
  testRegex: ".spec.ts$",
  transform: {
    "^.+\\.(t|j)s$": "ts-jest"
  },
  collectCoverage: true,
  coverageDirectory: "../coverage",
  testEnvironment: "node",
  moduleNameMapper: {
    "^jose/(.*)$": "<rootDir>/../node_modules/jose/dist/node/cjs/$1",
    "^~/(.*)$": "<rootDir>/$1"
  },
  coverageThreshold: {
    global: {
      branches: 1,
      functions: 1,
      lines: 1,
      statements: 1
    }
  }
}