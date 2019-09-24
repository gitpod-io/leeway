import * as React from "react";
import { BuildEventSourcePromiseClient } from "../protocol/ui-protocol_grpc_web_pb";
import { Package, PackageMetadata, PackageStatus } from "../protocol/protocol_pb";
import { RegisterReq } from "../protocol/ui-protocol_pb";
import { Grid } from 'semantic-ui-react';
import { Graph } from "./graph";
import { TerminalCollection } from "./terminals";

interface AppProps {
    client?: BuildEventSourcePromiseClient;
}

interface AppState {
    activeBuild?: Package;
    packageStatus: Map<string, PackageStatus>;
}


export class App extends React.Component<AppProps, AppState> {

    constructor(p: AppProps) {
        super(p);
        this.state = {
            packageStatus: new Map<string, PackageStatus>()
        };
    }

    render() {
        const terminals = Array
            .from(this.state.packageStatus.entries())
            .map((c, i) => {
                let status = "inactive";
                if (c[1] == PackageStatus.BUILDING) {
                    status = "active";
                } else if (c[1] == PackageStatus.BUILT) {
                    status = "success";
                }

                return <TerminalCollection.Terminal
                    status={status as any}
                    title={c[0]}
                    id={c[0]}
                    key={`e${i}`} />
            }

        );

        return <Grid centered={true}>
            <Grid.Row>
                <Grid.Column width={8}>
                    <Graph root={this.state.activeBuild} status={this.state.packageStatus} />
                </Grid.Column>
                <Grid.Column width={8}>
                    <TerminalCollection>
                        { terminals as any }
                    </TerminalCollection>
                </Grid.Column>
            </Grid.Row>
        </Grid>
    }

    componentDidMount() {
        this.establishListener()
    }

    protected async establishListener() {
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
                // term.write(content);
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

}