import { App } from "./app";
import * as ReactDOM from 'react-dom';
import * as React from "react";
import { WithClient } from "./client";

import 'semantic-ui-css/semantic.min.css'

ReactDOM.render(<WithClient><App /></WithClient>, document.getElementById("root"));