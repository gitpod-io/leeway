let packages = [];

let deps = [];
for(let i = 0; i < 10; i++) {
  const name = "hello-"+i;
  deps.push(name);
  packages.push({
    name: name,
    type: "generic",
    config: {
      commands: [
        ["echo", "hello from "+i]
      ]
    }
  });
}

packages.push({
  name: "all",
  type: "generic",
  deps: deps.map(d => ":" + d),
})
