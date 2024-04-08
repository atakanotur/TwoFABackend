const mongoose = require("mongoose");
let instance = null;
class Database {
  constructor() {
    if (!instance) {
      this.mongoConnection = null;
      instance = this;
    }
    return instance;
  }

  async connect(options) {
    try {
      console.log("Database connecting...");
      let db = await mongoose.connect(options.CONNECTION_STRING);

      this.mongoConnection = db;
      console.log("Database connected!");
    } catch (error) {
      console.log("Database conntection failed!", error);
      process.exit(1);
    }
  }
}

module.exports = Database;
