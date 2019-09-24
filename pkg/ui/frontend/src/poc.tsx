import * as React from "react";
import * as d3 from "d3";
import { ELK, ElkPoint, ElkNode, ElkExtendedEdge } from "elkjs/lib/elk-api";
import ElkConstructor from 'elkjs/lib/elk-api';
import { BuildEventSourcePromiseClient } from "../protocol/ui-protocol_grpc_web_pb";
import { RegisterReq } from "../protocol/ui-protocol_pb";
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { Graph } from "./graph";
import { Package, PackageMetadata, PackageStatus } from "../protocol/protocol_pb";
import { tickStep } from "d3";

interface AppState {
    activeBuild?: Package;
    packageStatus: Map<string, PackageStatus>;
}

interface AppProps {
    client?: BuildEventSourcePromiseClient;
    source?: string;
}

export class App extends React.Component<AppProps, AppState> {
    protected termContainer: HTMLDivElement;

    constructor(props: AppProps) {
        super(props);
        this.state = {
            packageStatus: new Map<string, PackageStatus>()
        };
    }

    async componentDidMount() {
        const term = new Terminal();
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        term.open(this.termContainer);
        fitAddon.fit();

        window.addEventListener('resize', () => fitAddon.fit());

        if (!this.props.client) {
            console.warn("no client");
        }

        const decoder = new TextDecoder();

        const req = new RegisterReq();
        const evt = await this.props.client.register(req);
        evt.on('data', m => {
            if (m.hasBuildLog()) {
                const lg = m.getBuildLog();
                let content = decoder.decode(lg.getData() as Uint8Array);
                content = content.replace(/\n/g, '\r\n');
                term.write(content);
            } else if (m.hasBuildStarted()) {
                this.setState({activeBuild: m.getBuildStarted().getPackage()});
            } else if (m.hasPackageBuildStarted()) {
                const started = m.getPackageBuildStarted();

                const status = this.state.packageStatus;
                status.set(started.getPackage().getFullname(), PackageStatus.BUILDING);
                this.setState({packageStatus: status});
            } else if (m.hasPackageBuildFinished()) {
                const finished = m.getPackageBuildFinished();

                const status = this.state.packageStatus;
                status.set(finished.getPackage().getFullname(), PackageStatus.BUILT);
                this.setState({packageStatus: status});
            }
        });
        evt.on('end', () => console.log('end'));
    }

    render() {
        return <React.Fragment>
            <div className="term" ref={ref => this.termContainer = ref}></div>
            <Graph root={this.state.activeBuild} status={this.state.packageStatus} />
        </React.Fragment>;
    }

}