import * as React from "react";
import { Accordion, Placeholder } from 'semantic-ui-react';

export class TerminalCollection extends React.Component<TerminalCollection.Props, TerminalCollection.State> {

    constructor(p: TerminalCollection.Props) {
        super(p)
        this.state = {
            openTerminals: []
        }
    }

    render() {
        const children = React.Children.map(this.props.children, e => React.cloneElement(e as any, {
            active: e.props.status == "active"
                    || e.props.status == "failure"
                    || this.state.openTerminals.includes(e.props.id)
        }))
        return <Accordion styled>{children}</Accordion>;
    }

}

export namespace TerminalCollection {

    export interface Props {
        children?: TerminalCollection.Terminal[]
    }

    export interface State {
        openTerminals: string[]
    }

    export interface TerminalProps {
        id: string;
        title: string;
        status: "inactive" | "active" | "success" | "failure";

        active?: boolean
    }

    export class Terminal extends React.Component<TerminalProps, {}> {

        render() {
            return <React.Fragment>
                    <Accordion.Title active={this.props.active}>{this.props.title}</Accordion.Title>
                    <Accordion.Content active={this.props.active}>
                        <Placeholder>
                            <Placeholder.Header image>
                                <Placeholder.Line />
                                <Placeholder.Line />
                            </Placeholder.Header>
                            <Placeholder.Paragraph>
                                <Placeholder.Line />
                                <Placeholder.Line />
                                <Placeholder.Line />
                                <Placeholder.Line />
                            </Placeholder.Paragraph>
                        </Placeholder>
                    </Accordion.Content>
                </React.Fragment>
        }

    }

}
