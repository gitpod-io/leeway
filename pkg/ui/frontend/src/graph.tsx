import * as React from "react";
import * as d3 from "d3";
import { ELK, ElkPoint, ElkNode, ElkExtendedEdge } from "elkjs/lib/elk-api";
import ElkConstructor from 'elkjs/lib/elk-api';
import { BuildEventSourcePromiseClient } from "../protocol/ui-protocol_grpc_web_pb";
import { Package, PackageMetadata, PackageStatus } from "../protocol/protocol_pb";

type NodeStatus = "built" | "building" | "waiting";
interface Node {
    id: string
    label?: string
    status: NodeStatus
}

interface GraphProps {
    root: Package;
    status: Map<string, PackageStatus>;
}

export class Graph extends React.Component<GraphProps, {}> {
    protected ref: HTMLDivElement;
    protected canvas: HTMLCanvasElement;
    protected nodes: d3.Selection<SVGRectElement, ElkNode, SVGSVGElement, unknown> | undefined;
    protected edges: d3.Selection<SVGRectElement, ElkNode, SVGSVGElement, unknown> | undefined;
    protected elk: ELK;

    constructor(props: GraphProps) {
        super(props);
        this.elk = new ElkConstructor({
            algorithms: ['layered'],
            workerUrl: "elk/elk-worker.min.js",
        });
    }

    async componentDidMount() {
        var zoom = d3.zoom()
            .scaleExtent([1, 8]);

        const container = d3.select(this.ref).append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", "0 0 800 600")
            .call(zoom);
        container.append("svg:defs").append("svg:marker")
            .attr("id", "triangle")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 10)
            .attr("refY", 0)
            .attr("markerWidth", 4)
            .attr("markerHeight", 4)
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .style("fill", "black");

        this.nodes = container.selectAll("nodes");
        this.edges = container.selectAll("edges");

        // container.selectAll("text")
        //     .data(res.children, (n: ElkNode) => n.id)
        //     .enter()
        //     .append("text")
        //     .style("font-size", "10")
        //     .style("font-familty", "sans-serif")
        //     .style("text-align", "center")
        //     .style("color", "white")
        //     .attr("x", n => n.x + 2)
        //     .attr("y", n => n.y + 16)
        //     .attr("width", n => n.width)
        //     .attr("height", n => n.height - 4)
        //     .text(n => n.id);
        this.updateLayout();
    }

    protected async updateLayout() {
        if (!this.nodes) {
            return;
        }
        if (!this.props.root) {
            return;
        }

        const {rootNode, nodeMapping} = this.toElkGraph(this.props.root);

        const res = await this.elk.layout(rootNode, { layoutOptions: { direction: "right" } });

        const actualWidth = res.children.reduce<number>((m, e) => Math.max(m, e.x + e.width), 0);
        const actualHeight = res.children.reduce<number>((m, e) => Math.max(m, e.y + e.height), 0);
         d3.select(this.ref).selectAll("svg").attr("viewBox", `0 0 ${actualWidth} ${actualHeight}`);

        var edges = res.edges.map((edge: ElkExtendedEdge) => {
            const sec = edge.sections[0];

            const coords: ElkPoint[] = [];
            coords.push(sec.startPoint);
            (sec.bendPoints || []).forEach(p => coords.push(p));
            coords.push(sec.endPoint);
            return coords;
        });

        const fillNode = n => {
            const status = nodeMapping.get(n.id);
            let fill = "";
            if (status == PackageStatus.BUILDING) {
                fill = "#FFA646";
            } else if (status == PackageStatus.BUILT) {
                fill = "#33A9AC";
            } else {
                fill = "#F86041";
            }
            return fill;
        };

        this.nodes
            .data(res.children, (n: ElkNode) => n.id)
            .enter()
            .append("rect")
            .attr("x", n => n.x)
            .attr("y", n => n.y)
            .attr("width", n => n.width)
            .attr("height", n => n.height)
            .style("stroke", "white")
            .style("fill", fillNode)
            .exit().remove();

        this.nodes
            .transition()
            .duration(400)
            .style("fill", fillNode);

        this.edges
            .data(edges)
            .enter()
            .append("path")
            .attr("d", edge =>
                d3.line<ElkPoint>()
                    .x(p => p.x)
                    .y(p => p.y)
                    .curve(d3.curveStep)(edge))
            .attr("stroke", "#343779")
            .attr("stroke-width", 1)
            .attr("fill", "none")
            .attr("marker-end", "url(#triangle)")
            .exit().remove();
    }

    protected toElkGraph(root: Package): {rootNode: ElkNode, nodeMapping: Map<string, PackageStatus>} {
        let getDeps: (p: Package) => Package[];
        getDeps = p => {
            let r: Package[] = [];
            r.push(p);
            p.getDependenciesList().forEach(dep => r = r.concat(getDeps(dep)));
            return r;
        }

        const nodes = getDeps(root);

        const nodeMapping = new Map<string, PackageStatus>();
        nodes.forEach(m => nodeMapping.set(m.getMetadata().getFullname(), m.getStatus()));
        this.props.status.forEach((v, k) => nodeMapping.set(k, v));

        const graph: ElkNode = {
            id: "1",
            children: Array.from(nodes.values()).map(e => {
                const r: ElkNode = {
                    id: e.getMetadata().getFullname(),
                    width: 20, //this.canvas.getContext("2d").measureText(e.id).width,
                    height: 20,
                };
                return r;
            }),
            edges: Array.prototype.concat(...nodes.map((n, ni) => n.getDependenciesList().map((dep, di) => {
                let r: ElkExtendedEdge = {
                    id: `e${ni}.${di}`,
                    sources: [dep.getMetadata().getFullname()],
                    targets: [n.getMetadata().getFullname()],
                    sections: [],
                };
                return r;
            })))
        };

        return { rootNode: graph, nodeMapping };
    }

    componentDidUpdate() {
        this.updateLayout();
    }

    render() {
        const style = { width: "100%", height: "100%", };
        return <React.Fragment>
            <canvas style={{ display: "none" }} ref={mountPoint => (this.canvas = mountPoint)}></canvas>
            <div style={style} ref={mountPoint => (this.ref = mountPoint)} />
        </React.Fragment>;
    }

}