// based on https://github.com/kieler/klayjs-d3/tree/master/examples/miserables

const d3 = require('d3');
const klay = require('klayjs-d3');

function viewport() {
  var e = window,
    a = 'inner';
  if (!('innerWidth' in window)) {
    a = 'client';
    e = document.documentElement || document.body;
  }
  return {
    width: e[a + 'Width'],
    height: e[a + 'Height']
  }
}

var width = viewport().width,
    height = viewport().height;
var color = d3.scale.category20();
var zoom = d3.behavior.zoom()
    .on("zoom", redraw); 

var div = d3.select("body").append("div")	
    .attr("class", "tooltip")				
    .style("opacity", 0);

var svg = d3.select("body")
    .append("svg")
    .attr("width", width)
    .attr("height", height)
    .call(zoom)
    .append("g");

svg.append("defs")
    .append("marker")
    .attr("id", "arrowhead")
    .attr("markerWidth", "10")
    .attr("markerHeight", "7")
    .attr("refX", "10")
    .attr("refY", "3.5")
    .attr("orient", "auto")
    .append("polygon")
        .attr("points", "0 0, 10 3.5, 0 7");

var root = svg.append("g");

var layouter = klay.d3adapter();

d3.json("graph.json", function(error, graph) {

  layouter
      .nodes(graph.nodes)
      .links(graph.links)
      .size([width, height])
      .transformGroup(root)
      .options({
        edgeRouting: "ORTHOGONAL",
        mergeEdges: true
      });

  var link = root.selectAll(".link")
      .data(graph.links)
      .enter()
      .append("path")
      .attr("class", "link")
      .attr("d", "M0 0")
      .attr("marker-end", "url(#arrowhead)")
      .style("stroke-width", function(d) { return Math.sqrt(d.value); });

  var node = root.selectAll(".node")
      .data(graph.nodes)
      .enter()
      .append("rect")
      .attr("class", "node")
      .attr("width", 10)
      .attr("height", 10)
      .attr("x", 0)
      .attr("y", 0)
      .style("fill", function(d) { return color(d.typeid); })
      .on("mouseover", function(d, di) {
        div.transition()
          .duration(100)
          .style("opacity", .9);
        div.html(d.name)
          .style("left", (d3.event.pageX) + "px")
          .style("top", (d3.event.pageY - 28) + "px");
        d3.selectAll(".link").classed("link-hover", (l) => {
          return (l.path || []).includes(di);
        }).classed("link-fade", (l) => {
          return !(l.path || []).includes(di);
        });
      }).on("mouseout", function(d) {		
        div.transition()		
          .duration(500)		
          .style("opacity", 0);	
        d3.selectAll(".link").classed("link-hover", false).classed("link-fade", false);
      });

  node.append("title")
      .text(function(d) { return d.name; });

  layouter.on("finish", function(d) {
    link.transition().attr("d", function(d) {
      var path = "";
      path += "M" + d.sourcePoint.x + " " + d.sourcePoint.y + " ";
      d.bendPoints.forEach(function(bp, i) {
        path += "L" + bp.x + " " + bp.y + " ";
      });
      path += "L" + d.targetPoint.x + " " + d.targetPoint.y + " ";
      return path;
    });

    node.transition()
      .attr("x", function(d) { return d.x; })
      .attr("y", function(d) { return d.y; });    
  });
  
  layouter.start();
});

function redraw() {
  svg.attr("transform", "translate(" + d3.event.translate + ")" 
                          + " scale(" + d3.event.scale + ")");
};