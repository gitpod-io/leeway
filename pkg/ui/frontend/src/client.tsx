import * as React from "react";
import { BuildEventSourcePromiseClient } from "../protocol/ui-protocol_grpc_web_pb";

export class WithClient extends React.Component<{}, {}> {
    protected client: BuildEventSourcePromiseClient | undefined;

    constructor(p: {}) {
        super(p);
        this.client = new BuildEventSourcePromiseClient(`${window.location.protocol}//${window.location.host}:${window.location.port}`, null, null);
    }

    render() {
        const children = React.Children.map(this.props.children, e => React.cloneElement(e as any, {
            client: this.client ,
            source: "source-foo",
        }))
        return <React.Fragment>{children}</React.Fragment>
    }

}