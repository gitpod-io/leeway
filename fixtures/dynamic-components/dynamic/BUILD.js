const packages = [];

const withUpperCaseMessage = args.withUpperCaseMessage == "true";

if (withUpperCaseMessage) {
  const docker = {
    name: "message",
    type: "generic",
    srcs: ["message-input.txt"],
    config: {
      commands: [
        [
          "sh",
          "-c",
          "awk '{print toupper($0)}' < message-input.txt > message.txt",
        ],
      ],
    },
  };
  packages.push(docker);
} else {
  packages.push({
    name: "message",
    type: "generic",
    srcs: ["message-input.txt"],
    config: {
      commands: [
        [
          "sh",
          "-c",
          "awk '{print tolower($0)}' < message-input.txt > message.txt",
        ],
      ],
    },
  });
}
