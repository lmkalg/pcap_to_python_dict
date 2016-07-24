from walnut.core import agent

time = 0

# COMPLETAR: Reemplazar la traza vacia por una traza generada
# por el programa pcap2py.py, por ejemplo la traza trace_test1.py
# provista en el kickstart.
trace = [{"src": "192.168.1.22:53684",
          "ack": False,
          "dst": "23.235.46.175:https",
          "syn": True,
          "rst": False,
          "fin": False
          },
         {"src": "23.235.46.175:https",
          "ack": True,
          "dst": "192.168.1.22:53684",
          "syn": True,
          "rst": False,
          "fin": False
          },
         {"src": "192.168.1.22:53684",
          "ack": True,
          "dst": "23.235.46.175:https",
          "syn": False,
          "rst": False,
          "fin": False
          }]


def host(self, perception):
    """
      Retorna el nuevo estado de la conexion TCP en el diagrama de estado.
      Los estados posibles son:
      S = Closed | Listen | SynReceived | SynSent | Established | FinWait1 |
          FinWait2 | Closing | TimeWait | CloseWait | LastAck | Stop
    """
    global time
    global trace
    my_address = perception["my_address"]
    # estado actual de la conexion.
    state = perception["state"]

    #  Extrae de la traza el mensaje enviado, Stop si se termino la traza
    message = agent.types.Nothing()
    if time < len(trace):
        m = trace[time]
    else:
        return agent.types.Action(sent_message=message,
                                  new_state=agent.types.Stop())

    if trace[time]["src"] == my_address:
        message = agent.types.Segment(
            flags=agent.types.Flags(syn=m["syn"], ack=m["ack"], fin=m["fin"],
                                    rst=m["rst"]))

    flags = ""
    if m["ack"]:
        flags += "A"
    if m["fin"]:
        flags += "F"
    if m["rst"]:
        flags += "R"
    if m["syn"]:
        flags += "S"

    if m["dst"] == my_address:
        ## Caso mensaje recibido
        ## COMPLETAR: Actualizar la maquinda de estado:
        ## A partir del estado actual y los flags TCP
        ## se debe dedicir el nuevo estado del diagrama de estado
        ## - state.label obtiene un string con el nombre del estado
        ##   por ej: state.label == "SynSent" determina si el estado es SynSent
        ## - El modulo agent.types provee los diferentes estados posibles
        ##   por ejemplo: state = agent.types.Established()
        #pass
        if state.getLabel() == 'Listen':
          if flags == 'S':
            state = agent.types.SynReceived()
        elif state.getLabel == 'SynReceived':
          if flags == 'A':
            state = agent.types.Established()
          if flags == 'R':
            state = agent.types.Listen()
        elif state.getLabel() == 'SynSent':
          if flags == 'AR':
            state = agent.types.Closed()
          if flags == 'S':
            state = agent.types.SynReceived()
          if flags == 'AS':
            state = agent.types.Established()
        elif state.getLabel() == 'Established':
          if flags == 'F': 
            state = agent.types.CloseWait()
            #PARTU: No falta el R? 
        elif state.getLabel() == 'FinWait1':
          if flags == 'A':
            state = agent.types.FinWait2()
          if flags == 'F':
            state = agent.types.Closing()
          if flags == 'AF':
            state = agent.types.TimeWait()
        elif state.getLabel() == 'FinWait2':
          if flags == 'F':
            state = agent.types.TimeWait()
        elif state.getLabel() == 'Closing':
          if flags == 'A':
            state = agent.types.TimeWait()
        elif state.getLabel() == 'LastAck':
          if flags == 'A':
            state = agent.types.Closed()

    elif m["src"] == my_address:
        ## Caso mensaje enviado
        ## COMPLETAR: Actualizar la maquinda de estado:
        ## A partir del estado actual y los flags TCP se debe dedicir el
        ## nuevo estado a transitar en el diagrama de transicion de estado
        #pass
        if state.getLabel() == 'Closed':
          if flags == 'S':
            state = agent.types.SynSent()
        elif state.getLabel() == 'Listen':
          if flags == 'S':
            state = agent.types.SynSent()
        elif state.getLabel() == 'SynReceived':
          if flags == 'F':
            state = agent.types.FinWait1()
        elif state.getLabel() == 'Established':
          if flags == 'F':
            state = agent.types.FinWait1()
        elif state.getLabel() == 'CloseWait':
          if flags == 'F':
            state = agent.types.LastAck()



    else:
        # Que pasa si my_address no es ninguno de los dos hosts de la conexion?
        pass
    # Actualiza time
    time += 1
    # Retorna el mensaje enviado + el nuevo estado
    return agent.types.Action(sent_message=message, new_state=state)

agent.run(host)